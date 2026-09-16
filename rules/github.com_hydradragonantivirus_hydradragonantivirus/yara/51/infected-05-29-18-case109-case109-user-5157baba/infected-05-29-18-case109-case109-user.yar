rule _infected_05_29_18_case109_case109_user {
  meta:
    description = "case109 - file user.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "efdb09b3e16e1bd17bf2c991c45d285e2913afb9892f6844ef12586dfac0b22f"

  strings:
    $s1  = "if(!function_exists(\"TC9A16C47DA8EEE87\")){function TC9A16C47DA8EEE87($T059EC46CFE335260){$T059EC46CFE335260=base64_decode($T05" ascii
    $s2  = "KcGJpOQAAd1pYSnNEUXAxYzJVZ1UyOQAAamEyVjBPdzBLSkdsaFpHUgAAeVBXbHVaWFJmWVhSdmJpZwAAa1FWSkhWbHN3WFNrZ2ZIdwAAZ1pHbGxLQ0pGY25KdmNqbwB" ascii  
    $s3  = "if(!isset($_SESSION['nst']) or $_SESSION['nst'] != $password)" fullword ascii
    $s4  = "//PASSWORD CONFIGURATION" fullword ascii
    $s5  = "$chk_login = true;" fullword ascii
    $s6  = "if($chk_login == true)" fullword ascii
    $s7  = "<input type=password name=pass size=30>" fullword ascii
    $s8  = "@$pass = $_POST['pass'];" fullword ascii
    $s9  = "$password = \"youselee123@\";" fullword ascii
    $s10 = "SBNPPbnQUsD48EwI+LnAge2P/4TojnHj8cDt9z5AUgSKCIG9iGllsEAURGyMkdG1+FHAZsAIgETgM4QGUzYBnX3JlGMBjw6AhKAAQYm9keXxhOlx3K3wAsSwgdGSCgAB" ascii
    $s11 = "d1THgrhFGsPCBF8Qs8ykZASEBqyvSXqL+cDGv2tAxrwSzDjD0NRxIRXjw0PAR1GEtY29kWgRlHO9uHONYEG2OEj1wZiBtZYXgZD1ABHBKwCBvbnN1Ym1pdD0iJUB0aBQ" ascii
    $s12 = "BBZMlrySyAFxcB28nMVwnKyYCI4El/3Ml8gHBYVIwJYMA4U5UH99iaWcBgUMzXc9SRF3PUyFdzyBAMQvyXc/GbQ8y35kVTQ/4LwphCcIsPyw/DBMsPGhlgAMsYSRjIoD" ascii
    $s13 = "oIjrp8QH1X1BPU1RbJwHjMEAD0SEQL8V0N/An+bAcID0gMSxkBXEEYEBmaWxUYC9ldGMv+aUN8fwgCzIDwEAAX2Hn0u/SKTMAICBDMGW34tfnBAJU8CRZQGUFRACxBUA" ascii
    $s14 = "0dAxQb25jbGljG/5rPSIj4SZCYRgRKYMkAgFTCiAgtSQLAfMDRyzf0AESIA9kIAckLgMyB4gETyu0BEcinEQiPj4iAYs+IDxub2JyDfoDEmJveNFTYQvwAxQDSTEgJy4" ascii
    $s15 = "gIKogPZb+hMBtaxdxJyVQILQhAQEVlSZ5FSUMX8VgJuAsD4IgJ3cnB7IMWQQmd5AP0CJlZGl0MREgv3sK/yALMAqiMsD7X/tRMjEg8PK5nx/C+tYgDHoPd7Q+CoApDsQ" ascii
    $s16 = "if($pass == $password)" fullword ascii
    $s17 = "DE2E=strlen($T059EC46CFE335260);$T43D5686285035C13=__FILE__;$T43D5686285035C13=file_get_contents($T43D5686285035C13);$T6BBC58A3B" ascii
    $s18 = "jgP0EgIQqvCM9DkAjISWQHgCkNUmNhbGxf7CFPQF8MISgnAr8CsQkgSFB0AHA/Pg==\"));?>'));" fullword ascii
    $s19 = "<b>Your ip :D:</b> \".$_SERVER[\"REMOTE_ADDR\"].\"" fullword ascii
    $s20 = "sIJRRZiF9wBsxMXEEUs8EBmAuYWJyLjKVwhrgAbInPHByZQu0bWxrhTEnkgL0LwGgPjFBqoEbMQkgIAkMmScRdQFAb2Z0d2FyZX0wQJZQZW52KCdTAABFUlZFUl9TT0Z" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 100KB and
      (8 of them)
    ) or (all of them)
}