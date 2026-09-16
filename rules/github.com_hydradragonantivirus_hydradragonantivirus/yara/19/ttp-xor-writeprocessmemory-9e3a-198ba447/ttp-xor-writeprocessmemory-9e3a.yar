rule TTP_XOR_WriteProcessMemory_9e3a {
  strings:
    $key_9e3a = { c9 48 [2] fb 6a [2] fd 5f [2] d3 5f [2] ec 43 }

  condition:
    any of them
}