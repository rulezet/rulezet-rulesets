rule TTP_XOR_WriteProcessMemory_cdb8 {
  strings:
    $key_cdb8 = { 9a ca [2] a8 e8 [2] ae dd [2] 80 dd [2] bf c1 }

  condition:
    any of them
}