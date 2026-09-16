rule Win_Adware_Virtumonde_23
{
strings:
	$a0 = { 015453805fd43da04cac5d061018668346f2218c194effc8685de594d08d4dace9c29cf6ed4cf40f07101f60e6c5ec12024cd1061025fc4d6cd02d0d8ce840b5fefd8f02925d0c92504c195e427e3cdc }


condition:
	$a0
}