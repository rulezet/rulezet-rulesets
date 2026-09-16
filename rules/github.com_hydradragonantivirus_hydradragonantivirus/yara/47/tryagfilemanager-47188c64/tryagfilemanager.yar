rule TryagFileManager {
  meta:
    description = "mass-bot-exploite-master - file TryagFileManager.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-15"
    hash1       = "e32a7a80127f4d5be15a811c9f52b0698f2b73e5d65d48808462b074b9131856"

  strings:
    $x1  = "<span>Execute Command\\'s : </span><input name=\"cmd\" type=\"text\" id=\"c\" autofocus>" fullword ascii
    $x2  = "<div id=\"footer\"><p>Tryag File Manager Version <font color=\"red\">2.0</font>, Coded By <font color=\"red\">G-B</font><p>Mod" fullword ascii
    $s3  = "echo '<textarea cols=100 rows=30%>'.exec_all($_POST['cmd']).'</textarea>';" fullword ascii
    $s4  = "$handle = proc_open($command ,$descriptorspec , $pipes); // This will return the output to an array 'pipes'" fullword ascii
    $s5  = "<div id=\"footer\"><p>Tryag File Manager Version <font color=\"red\">2.0</font>, Coded By <font color=\"red\">G-B</font><p>Modde" ascii
    $s6  = "$output = shell_exec($command);" fullword ascii
    $s7  = "<form method=\"POST\" action=\"?path='.$currentpathen.'&exec\" onSubmit=\"Encoder(\\'c\\')\">" fullword ascii
    $s8  = "<div id=\"menu\"><a href=\"?path='.$currentpathen.'\">Home</a> - <a href=\"?path='.$currentpathen.'&cpanel\">Turbo Force</a> -" fullword ascii
    $s9  = "$handle = popen($command , \"r\"); // Open the command pipe for reading" fullword ascii
    $s10 = "$passwords = base64_decode($_POST['passwords']);" fullword ascii
    $s11 = "echo \"Tryag~ Username (<font color=red>$username</font>) Password (<font color=red>$password</font>)<br />\";" fullword ascii
    $s12 = "if(isset($_POST['usernames']) && isset($_POST['passwords'])){" fullword ascii
    $s13 = "ded by : Slotleet<br />Website: <font color=\"red\">Sec4ever.com</font></p></div>" fullword ascii
    $s14 = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
    $s15 = "function exec_all($command)" fullword ascii
    $s16 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete' || (isset($_GET['new']) && $_POST['type'] == 'file')){" fullword ascii
    $s17 = "header('Content-Disposition: attachment; filename=\"'.$_POST['name'].'\"');" fullword ascii
    $s18 = "$co = mysql_connect('localhost',$username,$password);" fullword ascii
    $s19 = "if(isset($_GET['option']) && $_POST['opt'] == 'download'){" fullword ascii
    $s20 = "\"<font size='2'>&quot;Listen to many, speak to a few.&quot;</font> <font size='1' color='gray'>William Shakespeare</font>\"," fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 80KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}