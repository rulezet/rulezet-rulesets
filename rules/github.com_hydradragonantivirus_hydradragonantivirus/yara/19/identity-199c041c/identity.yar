rule identity {
  meta:
    description = "case127 - file identity.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "aad4d52ca04dee99101dcd04409c75412e1fc1b43222f5b18c3344922d752a04"

  strings:
    $s1  = "$query = @unserialize(file_get_contents('http://ip-api.com/php/'.$ip));" fullword ascii
    $s2  = "} elseif ( isset($_SERVER['HTTP_X_FORWARDED_FOR']) && ! empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {" fullword ascii
    $s3  = "$(\"<div class=\\\"jFiler-item-others text-error\\\"><i class=\\\"icon-jfi-minus-circle\\\"></i> Error</div>\").hi" fullword ascii
    $s4  = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"  />" fullword ascii
    $s5  = "$ip = (isset($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';" fullword ascii
    $s6  = "<script type=\"text/javascript\" src=\"./ID/identity/js/jquery-latest.min.js\"></script>" fullword ascii
    $s7  = "<link href=\"./ID/identity/css/jquery.filer.css\" type=\"text/css\" rel=\"stylesheet\"  media=\"screen\" />" fullword ascii
    $s8  = "<script type=\"text/javascript\" src=\"./ID/identity/js/jquery.filer.min.js\"></script>" fullword ascii
    $s9  = "$(\"<div class=\\\"jFiler-item-others text-success\\\"><i class=\\\"icon-jfi-check-circle\\\"></i> Success</div>\"" fullword ascii
    $s10 = "filesSizeAll: \"Files you've choosed are too large! Please upload files up to {{fi-maxSize}} MB.\"" fullword ascii
    $s11 = "changeInput: '<div class=\"jFiler-input-dragDrop\"><div class=\"jFiler-input-inner\"><div class=\"jFiler-input-icon\"><i c" fullword ascii
    $s12 = "if ( isset($_SERVER['HTTP_CLIENT_IP']) && ! empty($_SERVER['HTTP_CLIENT_IP'])) {" fullword ascii
    $s13 = "// Get user IP address" fullword ascii
    $s14 = "this.getID(el).style.display='';" fullword ascii
    $s15 = "$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];" fullword ascii
    $s16 = "echo \"<form method='POST' enctype='multipart/form-data'>" fullword ascii
    $s17 = "<link rel=\"stylesheet\" href=\"./ID/dzx/css/loading.css\" media=\"screen\" />" fullword ascii
    $s18 = "filesSize: \"{{fi-name}} is too large! Please upload file up to {{fi-maxSize}} MB.\"," fullword ascii
    $s19 = "<link rel=\"stylesheet\" type=\"text/css\" href=\"./gg/zeb.css\">" fullword ascii
    $s20 = "<script type=\"text/javascript\" src=\"./ID/dzx/js/info.js\"></script>" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 40KB and
      (8 of them)
    ) or (all of them)
}