rule TTP_XOR_QUAD_CurrentVersionRun_2929 {
  strings:
    $key_2929 = { 7a 46 [2] 5e 48 [2] 75 64 [2] 5b 46 [2] 4f 5d [2] 40 47 [2] 5e 5a [2] 5c 5b [2] 47 5d [2] 5b 5a [2] 47 75 }

  condition:
    any of them
}