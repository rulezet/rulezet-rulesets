rule TTP_XOR_WriteProcessMemory_314d {
  strings:
    $key_314d = { 66 3f [2] 54 1d [2] 52 28 [2] 7c 28 [2] 43 34 }

  condition:
    any of them
}