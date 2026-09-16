rule TTP_XOR_WriteProcessMemory_eaae {
  strings:
    $key_eaae = { bd dc [2] 8f fe [2] 89 cb [2] a7 cb [2] 98 d7 }

  condition:
    any of them
}