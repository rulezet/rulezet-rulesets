rule TTP_XOR_WriteProcessMemory_3bc7 {
  strings:
    $key_3bc7 = { 6c b5 [2] 5e 97 [2] 58 a2 [2] 76 a2 [2] 49 be }

  condition:
    any of them
}