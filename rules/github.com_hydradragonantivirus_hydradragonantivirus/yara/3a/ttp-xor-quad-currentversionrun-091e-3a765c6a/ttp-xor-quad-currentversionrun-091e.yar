rule TTP_XOR_QUAD_CurrentVersionRun_091e {
  strings:
    $key_091e = { 5a 71 [2] 7e 7f [2] 55 53 [2] 7b 71 [2] 6f 6a [2] 60 70 [2] 7e 6d [2] 7c 6c [2] 67 6a [2] 7b 6d [2] 67 42 }

  condition:
    any of them
}