rule TTP_XOR_WriteProcessMemory_cad2 {
  strings:
    $key_cad2 = { 9d a0 [2] af 82 [2] a9 b7 [2] 87 b7 [2] b8 ab }

  condition:
    any of them
}