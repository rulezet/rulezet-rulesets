rule TTP_XOR_WriteProcessMemory_a43a {
  strings:
    $key_a43a = { f3 48 [2] c1 6a [2] c7 5f [2] e9 5f [2] d6 43 }

  condition:
    any of them
}