rule TTP_XOR_WriteProcessMemory_9fbf {
  strings:
    $key_9fbf = { c8 cd [2] fa ef [2] fc da [2] d2 da [2] ed c6 }

  condition:
    any of them
}