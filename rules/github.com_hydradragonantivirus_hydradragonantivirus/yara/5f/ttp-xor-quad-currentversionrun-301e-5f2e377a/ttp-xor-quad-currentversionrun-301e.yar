rule TTP_XOR_QUAD_CurrentVersionRun_301e {
  strings:
    $key_301e = { 63 71 [2] 47 7f [2] 6c 53 [2] 42 71 [2] 56 6a [2] 59 70 [2] 47 6d [2] 45 6c [2] 5e 6a [2] 42 6d [2] 5e 42 }

  condition:
    any of them
}