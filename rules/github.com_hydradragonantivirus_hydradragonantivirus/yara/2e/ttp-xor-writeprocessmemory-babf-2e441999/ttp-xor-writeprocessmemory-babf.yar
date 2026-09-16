rule TTP_XOR_WriteProcessMemory_babf {
  strings:
    $key_babf = { ed cd [2] df ef [2] d9 da [2] f7 da [2] c8 c6 }

  condition:
    any of them
}