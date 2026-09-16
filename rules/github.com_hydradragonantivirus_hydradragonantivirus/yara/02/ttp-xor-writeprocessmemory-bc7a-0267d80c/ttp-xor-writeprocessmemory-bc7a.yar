rule TTP_XOR_WriteProcessMemory_bc7a {
  strings:
    $key_bc7a = { eb 08 [2] d9 2a [2] df 1f [2] f1 1f [2] ce 03 }

  condition:
    any of them
}