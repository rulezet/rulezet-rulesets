rule TTP_XOR_QUAD_CurrentVersionRun_350e {
  strings:
    $key_350e = { 66 61 [2] 42 6f [2] 69 43 [2] 47 61 [2] 53 7a [2] 5c 60 [2] 42 7d [2] 40 7c [2] 5b 7a [2] 47 7d [2] 5b 52 }

  condition:
    any of them
}