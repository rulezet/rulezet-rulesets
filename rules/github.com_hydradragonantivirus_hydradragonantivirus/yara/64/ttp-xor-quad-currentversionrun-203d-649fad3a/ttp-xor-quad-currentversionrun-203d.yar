rule TTP_XOR_QUAD_CurrentVersionRun_203d {
  strings:
    $key_203d = { 73 52 [2] 57 5c [2] 7c 70 [2] 52 52 [2] 46 49 [2] 49 53 [2] 57 4e [2] 55 4f [2] 4e 49 [2] 52 4e [2] 4e 61 }

  condition:
    any of them
}