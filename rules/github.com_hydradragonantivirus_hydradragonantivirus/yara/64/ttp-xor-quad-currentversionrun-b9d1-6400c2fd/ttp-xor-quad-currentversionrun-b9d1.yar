rule TTP_XOR_QUAD_CurrentVersionRun_b9d1 {
  strings:
    $key_b9d1 = { ea be [2] ce b0 [2] e5 9c [2] cb be [2] df a5 [2] d0 bf [2] ce a2 [2] cc a3 [2] d7 a5 [2] cb a2 [2] d7 8d }

  condition:
    any of them
}