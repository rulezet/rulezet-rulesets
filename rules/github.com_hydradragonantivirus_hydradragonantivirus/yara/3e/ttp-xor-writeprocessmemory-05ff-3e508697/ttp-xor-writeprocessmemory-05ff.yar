rule TTP_XOR_WriteProcessMemory_05ff {
  strings:
    $key_05ff = { 52 8d [2] 60 af [2] 66 9a [2] 48 9a [2] 77 86 }

  condition:
    any of them
}