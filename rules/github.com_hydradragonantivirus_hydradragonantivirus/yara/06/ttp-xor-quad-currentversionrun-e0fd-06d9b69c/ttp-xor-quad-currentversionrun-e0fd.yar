rule TTP_XOR_QUAD_CurrentVersionRun_e0fd {
  strings:
    $key_e0fd = { b3 92 [2] 97 9c [2] bc b0 [2] 92 92 [2] 86 89 [2] 89 93 [2] 97 8e [2] 95 8f [2] 8e 89 [2] 92 8e [2] 8e a1 }

  condition:
    any of them
}