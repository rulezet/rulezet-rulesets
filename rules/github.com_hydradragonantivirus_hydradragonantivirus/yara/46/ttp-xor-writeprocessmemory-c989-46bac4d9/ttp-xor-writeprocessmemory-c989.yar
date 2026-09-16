rule TTP_XOR_WriteProcessMemory_c989 {
  strings:
    $key_c989 = { 9e fb [2] ac d9 [2] aa ec [2] 84 ec [2] bb f0 }

  condition:
    any of them
}