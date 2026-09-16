import "math"
rule math_entropy_2 : info statistics {
	meta:
	        description = "Very low entropy - repeating sequence of couple of bytes"

	condition:
		math.entropy(0, filesize) >= 2 and
		math.entropy(0, filesize) < 3
}