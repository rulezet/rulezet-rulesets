rule TTP_XOR_QUAD_CurrentVersionRun_191e {
  strings:
    $key_191e = { 4a 71 [2] 6e 7f [2] 45 53 [2] 6b 71 [2] 7f 6a [2] 70 70 [2] 6e 6d [2] 6c 6c [2] 77 6a [2] 6b 6d [2] 77 42 }

  condition:
    any of them
}