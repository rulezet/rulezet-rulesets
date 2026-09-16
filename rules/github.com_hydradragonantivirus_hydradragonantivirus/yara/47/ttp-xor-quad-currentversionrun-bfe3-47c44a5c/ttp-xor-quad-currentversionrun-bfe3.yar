rule TTP_XOR_QUAD_CurrentVersionRun_bfe3 {
  strings:
    $key_bfe3 = { ec 8c [2] c8 82 [2] e3 ae [2] cd 8c [2] d9 97 [2] d6 8d [2] c8 90 [2] ca 91 [2] d1 97 [2] cd 90 [2] d1 bf }

  condition:
    any of them
}