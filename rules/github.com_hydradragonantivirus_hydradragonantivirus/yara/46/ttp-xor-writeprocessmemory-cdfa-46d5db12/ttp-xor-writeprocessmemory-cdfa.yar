rule TTP_XOR_WriteProcessMemory_cdfa {
  strings:
    $key_cdfa = { 9a 88 [2] a8 aa [2] ae 9f [2] 80 9f [2] bf 83 }

  condition:
    any of them
}