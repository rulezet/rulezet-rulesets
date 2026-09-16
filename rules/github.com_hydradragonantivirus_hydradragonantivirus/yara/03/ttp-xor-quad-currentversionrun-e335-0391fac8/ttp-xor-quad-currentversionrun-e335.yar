rule TTP_XOR_QUAD_CurrentVersionRun_e335 {
  strings:
    $key_e335 = { b0 5a [2] 94 54 [2] bf 78 [2] 91 5a [2] 85 41 [2] 8a 5b [2] 94 46 [2] 96 47 [2] 8d 41 [2] 91 46 [2] 8d 69 }

  condition:
    any of them
}