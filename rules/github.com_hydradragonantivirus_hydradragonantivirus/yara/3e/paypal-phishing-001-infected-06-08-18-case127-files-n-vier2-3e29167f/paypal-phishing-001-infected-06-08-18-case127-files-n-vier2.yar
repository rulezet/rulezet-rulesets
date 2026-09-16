rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier2 {
  meta:
    description = "case127 - file N_Vier2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "e6261f3642a19a3d73ab057136bd78fa05361532f922a8e62b5505987d7fa2a3"

  strings:
    $s1 = "header(\"location: Credit card.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
    $s2 = "$_SESSION['fnumber'] = $_POST['fnumber'];" fullword ascii
    $s3 = "$_SESSION['lname'] = $_POST['lname'];" fullword ascii
    $s4 = "$_SESSION['zip'] = $_POST['zip'];" fullword ascii
    $s5 = "$_SESSION['fname'] = $_POST['fname'];" fullword ascii
    $s6 = "$_SESSION['dob'] = $_POST['dob'];" fullword ascii
    $s7 = "$_SESSION['sort'] = $_POST['sort'];" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}