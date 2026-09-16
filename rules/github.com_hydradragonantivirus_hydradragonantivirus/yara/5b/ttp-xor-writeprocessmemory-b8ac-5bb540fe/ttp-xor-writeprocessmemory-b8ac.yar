rule TTP_XOR_WriteProcessMemory_b8ac {
  strings:
    $key_b8ac = { ef de [2] dd fc [2] db c9 [2] f5 c9 [2] ca d5 }

  condition:
    any of them
}