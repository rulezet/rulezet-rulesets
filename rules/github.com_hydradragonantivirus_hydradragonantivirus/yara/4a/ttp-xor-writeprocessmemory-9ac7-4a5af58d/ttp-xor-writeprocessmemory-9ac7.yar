rule TTP_XOR_WriteProcessMemory_9ac7 {
  strings:
    $key_9ac7 = { cd b5 [2] ff 97 [2] f9 a2 [2] d7 a2 [2] e8 be }

  condition:
    any of them
}