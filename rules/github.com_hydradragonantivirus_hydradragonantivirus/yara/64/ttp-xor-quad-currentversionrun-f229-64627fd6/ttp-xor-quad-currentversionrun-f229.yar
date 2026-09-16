rule TTP_XOR_QUAD_CurrentVersionRun_f229 {
  strings:
    $key_f229 = { a1 46 [2] 85 48 [2] ae 64 [2] 80 46 [2] 94 5d [2] 9b 47 [2] 85 5a [2] 87 5b [2] 9c 5d [2] 80 5a [2] 9c 75 }

  condition:
    any of them
}