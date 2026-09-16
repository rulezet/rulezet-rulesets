rule TTP_XOR_QUAD_CurrentVersionRun_0633 {
  strings:
    $key_0633 = { 55 5c [2] 71 52 [2] 5a 7e [2] 74 5c [2] 60 47 [2] 6f 5d [2] 71 40 [2] 73 41 [2] 68 47 [2] 74 40 [2] 68 6f }

  condition:
    any of them
}