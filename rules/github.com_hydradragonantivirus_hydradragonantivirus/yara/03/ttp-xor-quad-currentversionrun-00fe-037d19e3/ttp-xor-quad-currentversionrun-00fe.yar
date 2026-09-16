rule TTP_XOR_QUAD_CurrentVersionRun_00fe {
  strings:
    $key_00fe = { 53 91 [2] 77 9f [2] 5c b3 [2] 72 91 [2] 66 8a [2] 69 90 [2] 77 8d [2] 75 8c [2] 6e 8a [2] 72 8d [2] 6e a2 }

  condition:
    any of them
}