rule TTP_XOR_WriteProcessMemory_997a {
  strings:
    $key_997a = { ce 08 [2] fc 2a [2] fa 1f [2] d4 1f [2] eb 03 }

  condition:
    any of them
}