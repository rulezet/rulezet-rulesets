rule unlzx_table_three__32_big_64_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 01 00 00 00 03 00 00 00 07 00 00 00 0f 00 00 00 1f 00 00 00 3f 00 00 00 7f 00 00 00 ff 00 00 01 ff 00 00 03 ff 00 00 07 ff 00 00 0f ff 00 00 1f ff 00 00 3f ff 00 00 7f ff }

  condition:
    $a0
}