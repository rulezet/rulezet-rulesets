rule TTP_XOR_QUAD_CurrentVersionRun_50fe {
  strings:
    $key_50fe = { 03 91 [2] 27 9f [2] 0c b3 [2] 22 91 [2] 36 8a [2] 39 90 [2] 27 8d [2] 25 8c [2] 3e 8a [2] 22 8d [2] 3e a2 }

  condition:
    any of them
}