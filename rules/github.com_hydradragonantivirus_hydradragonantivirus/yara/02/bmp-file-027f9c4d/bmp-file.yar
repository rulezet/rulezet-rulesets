rule bmp_file
{
  strings:
    $magic = "BM"
  condition:
    $magic at 0
}