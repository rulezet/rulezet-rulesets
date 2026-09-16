rule Win_Trojan_Agent_35152
{
strings:
	$a0 = { 37414ee3bacf2e1ed2e04bc85c9a226c679302cafa3d3acc8709729d78dc35235fb758afdc4f8f955618aa15edfa8e3feb8a9ed6d9684b483fe901e49c345fdb2bb921cd55386a256f5c1faeee5d }


condition:
	$a0
}