rule TTP_XOR_QUAD_CurrentVersionRun_461f {
  strings:
    $key_461f = { 15 70 [2] 31 7e [2] 1a 52 [2] 34 70 [2] 20 6b [2] 2f 71 [2] 31 6c [2] 33 6d [2] 28 6b [2] 34 6c [2] 28 43 }

  condition:
    any of them
}