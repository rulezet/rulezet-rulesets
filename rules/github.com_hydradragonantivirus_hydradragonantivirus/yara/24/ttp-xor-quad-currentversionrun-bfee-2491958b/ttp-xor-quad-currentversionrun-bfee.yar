rule TTP_XOR_QUAD_CurrentVersionRun_bfee {
  strings:
    $key_bfee = { ec 81 [2] c8 8f [2] e3 a3 [2] cd 81 [2] d9 9a [2] d6 80 [2] c8 9d [2] ca 9c [2] d1 9a [2] cd 9d [2] d1 b2 }

  condition:
    any of them
}