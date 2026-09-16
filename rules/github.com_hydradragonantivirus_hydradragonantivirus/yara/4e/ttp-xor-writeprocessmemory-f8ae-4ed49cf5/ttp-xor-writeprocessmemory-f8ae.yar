rule TTP_XOR_WriteProcessMemory_f8ae {
  strings:
    $key_f8ae = { af dc [2] 9d fe [2] 9b cb [2] b5 cb [2] 8a d7 }

  condition:
    any of them
}