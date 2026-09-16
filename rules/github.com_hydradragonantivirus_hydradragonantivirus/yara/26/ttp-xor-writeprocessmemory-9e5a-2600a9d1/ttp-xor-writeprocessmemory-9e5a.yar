rule TTP_XOR_WriteProcessMemory_9e5a {
  strings:
    $key_9e5a = { c9 28 [2] fb 0a [2] fd 3f [2] d3 3f [2] ec 23 }

  condition:
    any of them
}