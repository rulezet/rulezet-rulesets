rule TTP_XOR_QUAD_CurrentVersionRun_b9cb {
  strings:
    $key_b9cb = { ea a4 [2] ce aa [2] e5 86 [2] cb a4 [2] df bf [2] d0 a5 [2] ce b8 [2] cc b9 [2] d7 bf [2] cb b8 [2] d7 97 }

  condition:
    any of them
}