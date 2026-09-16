rule IsPhp {
  strings:
    $php = /<\?[^x]/

  condition:
    $php and filesize < 5MB
}