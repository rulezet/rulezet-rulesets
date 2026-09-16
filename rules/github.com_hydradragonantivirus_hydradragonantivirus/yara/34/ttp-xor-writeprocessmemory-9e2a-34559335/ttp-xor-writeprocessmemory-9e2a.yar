rule TTP_XOR_WriteProcessMemory_9e2a {
  strings:
    $key_9e2a = { c9 58 [2] fb 7a [2] fd 4f [2] d3 4f [2] ec 53 }

  condition:
    any of them
}