rule TTP_XOR_QUAD_CurrentVersionRun_050e {
  strings:
    $key_050e = { 56 61 [2] 72 6f [2] 59 43 [2] 77 61 [2] 63 7a [2] 6c 60 [2] 72 7d [2] 70 7c [2] 6b 7a [2] 77 7d [2] 6b 52 }

  condition:
    any of them
}