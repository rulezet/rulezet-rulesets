rule TTP_XOR_WriteProcessMemory_98cc {
  strings:
    $key_98cc = { cf be [2] fd 9c [2] fb a9 [2] d5 a9 [2] ea b5 }

  condition:
    any of them
}