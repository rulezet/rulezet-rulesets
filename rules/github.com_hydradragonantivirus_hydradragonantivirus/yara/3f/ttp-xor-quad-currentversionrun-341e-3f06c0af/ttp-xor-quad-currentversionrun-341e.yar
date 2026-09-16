rule TTP_XOR_QUAD_CurrentVersionRun_341e {
  strings:
    $key_341e = { 67 71 [2] 43 7f [2] 68 53 [2] 46 71 [2] 52 6a [2] 5d 70 [2] 43 6d [2] 41 6c [2] 5a 6a [2] 46 6d [2] 5a 42 }

  condition:
    any of them
}