rule TTP_XOR_QUAD_CurrentVersionRun_3229 {
  strings:
    $key_3229 = { 61 46 [2] 45 48 [2] 6e 64 [2] 40 46 [2] 54 5d [2] 5b 47 [2] 45 5a [2] 47 5b [2] 5c 5d [2] 40 5a [2] 5c 75 }

  condition:
    any of them
}