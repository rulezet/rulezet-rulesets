rule TTP_XOR_QUAD_CurrentVersionRun_30fe {
  strings:
    $key_30fe = { 63 91 [2] 47 9f [2] 6c b3 [2] 42 91 [2] 56 8a [2] 59 90 [2] 47 8d [2] 45 8c [2] 5e 8a [2] 42 8d [2] 5e a2 }

  condition:
    any of them
}