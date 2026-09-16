rule TTP_XOR_QUAD_CurrentVersionRun_392a {
  strings:
    $key_392a = { 6a 45 [2] 4e 4b [2] 65 67 [2] 4b 45 [2] 5f 5e [2] 50 44 [2] 4e 59 [2] 4c 58 [2] 57 5e [2] 4b 59 [2] 57 76 }

  condition:
    any of them
}