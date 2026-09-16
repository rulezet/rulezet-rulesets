rule XProtect_macos_snowdock_crypt {
  meta:
    description = "MACOS.SNOWDOCK"

  strings:
    $key_1 = { 1d 82 b8 c7 6c 84 7f f6 54 29 5b 72 01 39 02 69 }
    $iv_1  = { 99 ed 52 00 8e ce d6 de 1d ba 5b 72 51 30 39 ae }

  condition:
    any of them
}