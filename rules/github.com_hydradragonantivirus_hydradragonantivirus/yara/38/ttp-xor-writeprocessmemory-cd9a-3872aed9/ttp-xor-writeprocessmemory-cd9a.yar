rule TTP_XOR_WriteProcessMemory_cd9a {
  strings:
    $key_cd9a = { 9a e8 [2] a8 ca [2] ae ff [2] 80 ff [2] bf e3 }

  condition:
    any of them
}